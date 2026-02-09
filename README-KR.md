# kubectl-why

**빠르고 오프라인 우선 Kubernetes 보안 결정 설명 도구**

kubectl-why는 정적 분석과 명확하고 읽기 쉬운 출력을 사용하여 **Kubernetes 리소스가 보안 정책에 의해 차단된 이유**를 설명합니다.

이 도구는 **스캐너가 아닌 추론 CLI**이며, **기본적으로 오프라인**으로 작동하고 **kubectl 플러그인**으로 자연스럽게 통합됩니다.

---

## 설치

### Krew를 통한 설치 (권장)

```bash
kubectl krew install why
```

### 수동 설치

[GitHub Releases](https://github.com/opensource-alison/why-blocked/releases)에서 최신 바이너리를 다운로드하세요:

```bash
# macOS/Linux
curl -LO https://github.com/opensource-alison/why-blocked/releases/latest/download/kubectl-why-$(uname -s)-$(uname -m)
chmod +x kubectl-why-*
sudo mv kubectl-why-* /usr/local/bin/kubectl-why

# 설치 확인
kubectl why version
```

### 소스에서 빌드

소스 빌드(개발자용): 빌드 관련 내용은 사용 가이드에 정리했습니다: [docs/usage-guide-kr.md](docs/usage-guide-kr.md).

---

## 빠른 시작

```bash
# 리소스가 차단된 이유 확인
kubectl why explain deployment my-app

# 최근 보안 결정 목록 조회
kubectl why decision list

# 특정 결정의 세부 정보 조회
kubectl why decision get <decision-id>

# 매니페스트 파일 평가 (오프라인, 클러스터 불필요)
kubectl why eval -f deployment.yaml

# 도구 탐색을 위한 테스트 결정 생성
kubectl why mock create test-app
kubectl why explain test-app
```

---

## 기능

- ✅ **오프라인 우선** – `eval` 명령으로 클러스터 접근 없이 작동
- ✅ **빠른 정적 분석** – 밀리초 단위로 차단 결정 설명
- ✅ **읽기 쉬운 출력** – 명확한 위반 사항, 증거, 수정 제안
- ✅ **다국어 지원** – 영어, 한국어, 일본어, 중국어, 스페인어 출력
- ✅ **JSON 출력** – CI/CD 자동화를 위한 구조화된 데이터
- ✅ **선택적 AI 설명** – `--ai` 플래그로 향상된 요약 제공
- ✅ **선택적 CVE/SBOM 스캔** – `--scan` 플래그로 실시간 스캔 결과 첨부

---

## 주요 명령어

| 명령어 | 설명 |
|--------|------|
| `kubectl why explain <name>` | Deployment가 차단된 이유 설명 (kind=Deployment 가정) |
| `kubectl why explain pod <name>` | Pod가 차단된 이유 설명 |
| `kubectl why decision list` | 최근 보안 결정 목록 조회 (최대 10개) |
| `kubectl why decision get <id>` | ID로 특정 결정 조회 |
| `kubectl why eval -f <file>` | YAML 매니페스트 오프라인 평가 (클러스터 불필요) |
| `kubectl why mock create <name>` | 테스트용 모의 차단 결정 생성 |
| `kubectl why help` | 모든 도움말 주제 표시 |
| `kubectl why version` | 버전 정보 표시 |

---

## 출력 예시

### 텍스트 출력 (기본)

```bash
$ kubectl why explain deployment my-app

WHY: Resource blocked: 1 critical, 1 high severity violations found
STATUS: BLOCKED

RESOURCE: Deployment/my-app
NAMESPACE: production
DECISION: dec-a1b2c3d4
TIME: 2026-02-09T10:30:00Z

VIOLATIONS (2):
1) [CRITICAL] Privileged Container
   What: Container 'nginx' runs in privileged mode, which grants access to all
   host devices and bypasses security boundaries.
   Evidence:
     - (K8S_FIELD) spec.template.spec.containers[0].securityContext.privileged:
       privileged: true
   Fix (minimal):
     - Disable privileged mode: Set securityContext.privileged: false

2) [HIGH] Missing runAsNonRoot
   What: Container 'nginx' does not enforce running as a non-root user.
   Evidence:
     - (K8S_FIELD) spec.template.spec.containers[0].securityContext.runAsNonRoot:
       not set or false
   Fix (minimal):
     - Set securityContext.runAsNonRoot: true for container 'nginx'
```

### JSON 출력

```bash
$ kubectl why explain deployment my-app -o json

{
  "schemaVersion": "v1",
  "decision": {
    "id": "dec-a1b2c3d4",
    "timestamp": "2026-02-09T10:30:00Z",
    "status": "BLOCKED",
    "summary": "Resource blocked: 1 critical, 1 high severity violations found",
    "resource": {
      "kind": "Deployment",
      "name": "my-app",
      "namespace": "production"
    },
    "violations": [...]
  }
}
```

---

## 선택적 기능

### 다국어 출력

```bash
# 한국어
kubectl why --lang ko explain deployment my-app

# 일본어
kubectl why --lang ja explain deployment my-app

# 중국어
kubectl why --lang zh explain deployment my-app

# 스페인어
kubectl why --lang es explain deployment my-app
```

지원 언어: `en` (기본값), `ko`, `ja`, `zh`, `es`

`--lang` 플래그가 지정되지 않으면 `LC_ALL` 또는 `LANG` 환경 변수에서 자동 감지됩니다.

### AI 기반 설명

AI 생성 요약 및 액션 아이템 추가:

```bash
# API 키 설정
export WHY_AI_API_KEY=your-openai-api-key

# AI 향상 설명 받기
kubectl why --ai explain deployment my-app
```

**요구사항:**
- Python 3.x 설치 (`python3` 또는 `python`으로 자동 감지)
- OpenAI API 키 (또는 호환 가능한 제공자)

**선택적 설정:**
```bash
# 사용자 정의 Python 경로 사용
export WHY_WORKER_COMMAND="python3 /path/to/worker/main.py"

# 다른 AI 제공자 사용
export WHY_AI_PROVIDER=gemini
export WHY_GEMINI_API_KEY=your-gemini-key
```

자세한 설정은 [docs/ai-worker-dev-kr.md](docs/ai-worker-dev-kr.md)를 참조하세요.

### 외부 취약점 스캔

외부 스캐너의 실시간 CVE 및 SBOM 데이터 첨부:

```bash
# CVE 스캔 (trivy 필요)
kubectl why --scan cve explain deployment my-app

# SBOM 생성 (syft 필요)
kubectl why --scan sbom explain deployment my-app

# 두 스캐너 모두 사용
kubectl why --scan cve,sbom explain deployment my-app
```

**설치:**
```bash
# macOS
brew install trivy syft

# Linux
# https://trivy.dev 및 https://github.com/anchore/syft 참조
```

스캐너가 설치되어 있지 않으면 경고를 표시하고 스캔 데이터 없이 계속 진행합니다.

---

## 오프라인 매니페스트 평가

클러스터 접근 없이 Kubernetes YAML 파일 평가:

```bash
# 배포 매니페스트 평가
kubectl why eval -f deployment.yaml

# JSON 출력으로 평가
kubectl why -o json eval -f deployment.yaml

# 네임스페이스 재정의
kubectl why eval -f deployment.yaml -n production
```

**종료 코드:**
- `0` = ALLOWED (리소스가 보안 요구사항 충족)
- `1` = ERROR (잘못된 파일, 파싱 오류 등)
- `2` = BLOCKED (리소스에 보안 위반 사항 있음)

**CI/CD 통합:**
```bash
#!/bin/bash
# 매니페스트가 보안 정책을 위반하면 파이프라인 실패
for manifest in k8s/*.yaml; do
    if ! kubectl why eval -f "$manifest"; then
        echo "❌ FAILED: $manifest has security violations"
        exit 1
    fi
done
echo "✅ All manifests passed security checks"
```

포괄적인 예시는 [docs/usage-guide-kr.md](docs/usage-guide-kr.md)를 참조하세요.

---

## 보안 정책

kubectl-why는 다음 정책에 대해 리소스를 평가합니다:

| 정책 ID | 심각도 | 검사 항목 |
|---------|---------|-----------|
| POL-SEC-001 | CRITICAL | 권한 있는 컨테이너 |
| POL-SEC-002 | HIGH | HostPath 볼륨 |
| POL-SEC-003 | HIGH | runAsNonRoot 설정 누락 |
| POL-SEC-004 | HIGH | 이미지 태그가 `:latest`이거나 누락됨 |

---

## 전역 플래그

```bash
--dir <path>          결정 저장 디렉토리 (기본값: ~/.kubectl-why/decisions)
--lang <code>         출력 언어: en, ko, ja, zh, es (설정하지 않으면 자동 감지)
-o, --output <fmt>    출력 형식: text, json (기본값: text)
--scan <modes>        스캐너 활성화: cve, sbom (쉼표로 구분)
--ai                  AI 생성 설명 추가 (WHY_AI_API_KEY 필요)
--quiet               상태 메시지 억제 (경고/오류는 유지)
--no-color            색상 출력 비활성화
```

---

## 문서

- **[사용 가이드](docs/usage-guide-kr.md)** – 명령어/옵션 설명과 예시 모음
- **[AI 워커 개발 문서](docs/ai-worker-dev-kr.md)** – 선택적 AI 보강 기능 설정 및 워커 연동(개발자용)
- **[AI 제공자 확장](docs/extending-ai-providers-kr.md)** – 새로운 AI 제공자 추가 방법(개발자용)

---

## 철학

kubectl-why는 의도적으로 집중된 도구입니다:

- **빠르고 로컬** – 오프라인 우선, 기본적으로 외부 종속성 없음
- **결정 설명** – 스캐너, 플랫폼, 런타임 분석기가 아님
- **읽기 쉬움** – 기술적 덤프보다 명확한 추론
- **최소 범위** – "왜 차단되었는가?"에 답하며 그 이상은 하지 않음

---

## 예시

### 예시 1: 배포가 차단된 이유 확인

```bash
kubectl why explain deployment nginx-app
```

### 예시 2: 최근 결정 목록 조회

```bash
kubectl why decision list
```

### 예시 3: 한국어로 결정 세부 정보 조회

```bash
kubectl why --lang ko decision get dec-12345
```

### 예시 4: CI/CD에서 매니페스트 평가

```bash
kubectl why eval -f k8s/deployment.yaml
if [ $? -eq 2 ]; then
  echo "Deployment has security violations"
  exit 1
fi
```

### 예시 5: CVE 스캔과 함께 AI 향상 설명

```bash
export WHY_AI_API_KEY=sk-...
kubectl why --ai --scan cve explain deployment my-app
```

---

## 지원

- **이슈:** https://github.com/opensource-alison/why-blocked/issues
- **토론:** https://github.com/opensource-alison/why-blocked/discussions
- **문서:** `kubectl why help` 실행하여 내장 도움말 확인

---

## 라이선스

MIT – 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.

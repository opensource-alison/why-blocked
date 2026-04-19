# kubectl-why

Kubernetes 리소스가 왜 차단되었는지 설명하고, 수정 방법을 안내하는 kubectl 플러그인입니다.

## 주요 기능

- CIS Kubernetes Benchmark와 Pod Security Standards에 근거한 14개 보안 규칙 + 1개 권고사항으로 매니페스트를 평가합니다
- 리소스를 차단한 admission 시스템을 감지합니다: PSA, Kyverno, Gatekeeper, RBAC, 일반 admission webhook
- 표준 참조와 함께 복사 가능한 YAML 수정 예시를 제공합니다

## 빠른 시작

```bash
# 배포 전 매니페스트 검사
kubectl why eval -f deployment.yaml

# kubectl apply 거부 원인 진단
kubectl apply -f pod.yaml 2>&1 | kubectl why diagnose -
```

## 설치

```bash
# 소스에서 설치
go install github.com/opensource-alison/why-blocked/cmd/why@latest
```

또는 [Releases](../../releases) 페이지에서 바이너리를 다운로드하세요.

## 명령어

| 명령어 | 설명 |
| --- | --- |
| `eval -f <file>` | 매니페스트를 보안 규칙으로 평가 |
| `diagnose` | 리소스를 차단한 admission 시스템 감지 |
| `explain <name>` | 저장된 리소스의 차단 이유 설명 (`Deployment` 가정) |
| `explain <kind> <name>` | 특정 kind를 지정하여 차단 이유 설명 |
| `decision list` | 최근 보안 결정 목록 조회 |
| `decision get <id>` | 특정 결정의 상세 정보 조회 |
| `mock create <name>` | 테스트용 모의 결정 생성 |
| `help [topic]` | 특정 주제의 도움말 표시 |
| `version` | 버전 정보 표시 |

## 보안 규칙

| 규칙 ID | 검사 항목 | 심각도 | 기준 |
| --- | --- | --- | --- |
| `POL-SEC-001` | 특권(privileged) 컨테이너 | `CRITICAL` | `CIS 5.2.1`, `PSA restricted` |
| `POL-SEC-002` | HostPath 볼륨 | `HIGH` | `CIS 5.2.8`, `PSA baseline` |
| `POL-SEC-003` | `runAsNonRoot` 미설정 | `HIGH` | `CIS 5.2.6`, `PSA restricted` |
| `POL-SEC-004` | 이미지 태그 `:latest` 또는 미지정 | `HIGH` | `CIS 5.5.1` |
| `POL-SEC-005` | `hostPID` | `HIGH` | `CIS 5.2.2`, `PSA baseline` |
| `POL-SEC-006` | `hostNetwork` | `HIGH` | `CIS 5.2.4`, `PSA baseline` |
| `POL-SEC-007` | `hostIPC` | `HIGH` | `CIS 5.2.3`, `PSA baseline` |
| `POL-SEC-008` | 위험한 capabilities | `HIGH` | `CIS 5.2.7`, `PSA restricted` |
| `POL-SEC-009` | `allowPrivilegeEscalation` 미비활성화 | `MEDIUM` | `CIS 5.2.5`, `PSA restricted` |
| `POL-SEC-010` | root(UID 0)로 실행 | `HIGH` | `CIS 5.2.6`, `PSA restricted` |
| `POL-RBAC-001` | RBAC 와일드카드 권한 | `CRITICAL` | `CIS 5.1.3` |
| `POL-RBAC-002` | Secret 무제한 접근 | `HIGH` | `CIS 5.1.2` |
| `POL-RBAC-003` | `pods/exec` 권한 | `HIGH` | `CIS 5.1.3` |
| `POL-RBAC-004` | `cluster-admin` 바인딩 | `CRITICAL` | `CIS 5.1.1` |
| `ADV-NET-001` | NetworkPolicy 미확인 | `INFO` | `CIS 5.3.2` |

모든 규칙은 공개된 보안 기준을 참조합니다. INFO 수준의 권고사항은 종료 코드나 차단 상태에 영향을 주지 않습니다.

## 지원 리소스

다음 Kubernetes 리소스 타입을 분석합니다:

- Pod 계열: `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ReplicaSet`
- RBAC: `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`

## 정책 엔진 감지

| 엔진 | 신뢰도 |
| --- | --- |
| Pod Security Admission (PSA) | 높음 |
| Kyverno | 높음 |
| Gatekeeper / OPA | 높음 |
| RBAC Forbidden | 높음 |
| 일반 Webhook | 중간 |

```bash
kubectl apply -f pod.yaml 2>&1 | kubectl why diagnose -

# 차단 원인 감지 + 매니페스트 평가를 동시에 수행
kubectl why diagnose --error "denied the request" -f pod.yaml
```

## 출력 형식

`--output text`가 기본값입니다:

```text
$ kubectl why eval -f testdata/safe-deployment.yaml
WHY: Resource meets security requirements with 1 advisory
STATUS: ALLOWED
```

자동화를 위해 `--output json`을 사용할 수 있습니다:

```json
{
  "schemaVersion": "v1",
  "decision": {
    "status": "ALLOWED",
    "violations": [
      {
        "policyId": "ADV-NET-001",
        "severity": "INFO"
      }
    ]
  }
}
```

## 다국어 지원

5개 언어를 지원하며, 각 언어별 119개의 번역 문자열이 제공됩니다:

- `en` (영어)
- `ko` (한국어)
- `ja` (일본어)
- `zh` (중국어 간체)
- `es` (스페인어)

```bash
kubectl why eval -f pod.yaml --lang ko
```

## 선택적 기능

### AI 보강 설명

```bash
export WHY_AI_API_KEY=your-key
kubectl why eval -f pod.yaml --ai
```

AI는 표현만 개선합니다. 규칙 평가, 심각도, 종료 코드는 변경하지 않습니다. 내장 워커는 OpenAI, Gemini, Claude 제공자를 지원합니다.

### CVE / SBOM 스캔

```bash
kubectl why eval -f pod.yaml --scan cve,sbom
```

`trivy`와 `syft`가 설치되어 있어야 합니다.

## 설계 원칙

- **오프라인 우선**: 핵심 평가와 진단은 클러스터 접근이나 외부 서비스 없이 동작합니다
- **증거 기반**: 증거가 불충분하면 추측하지 않고 `Unknown`을 반환합니다
- **기준 근거 명시**: 모든 규칙이 CIS 또는 PSA를 참조하며, 주관적 점수는 없습니다
- **설명 엔진**: admission controller를 대체하지 않고 보완합니다

## 프로젝트 구조

- `cmd/why/` — CLI 진입점 및 서브커맨드
- `internal/eval/` — 오프라인 규칙 평가 엔진
- `internal/detect/` — admission 차단 감지 엔진
- `internal/decision/` — 결정 스키마 및 저장 타입
- `internal/output/` — 텍스트 및 JSON 렌더링
- `internal/i18n/` — 내장 로케일 파일 및 번역 로딩
- `internal/repository/` — 로컬 결정 저장소
- `internal/scan/` — Trivy 및 Syft 연동
- `internal/ui/` — 터미널 색상 및 서식
- `tools/why-worker/` — 선택적 Python AI 워커

## 라이선스

MIT License. [LICENSE](LICENSE)를 참조하세요.
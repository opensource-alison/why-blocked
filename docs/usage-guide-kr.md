# `kubectl why eval`을 사용한 오프라인 평가

`eval` 명령은 클러스터 접근 없이 Kubernetes YAML 매니페스트의 오프라인 보안 정책 평가를 가능하게 합니다.

## 기능

- ✅ **오프라인 우선**: Kubernetes 클러스터 불필요
- ✅ **실제 규칙 평가**: 온라인 검사와 동일한 평가자 사용
- ✅ **영구 결정**: 히스토리 추적을 위해 저장소에 저장됨
- ✅ **다중 출력 형식**: 텍스트 (기본값) 또는 JSON
- ✅ **종료 코드**: ALLOWED는 0, BLOCKED는 2, 오류는 1

## 사용법

### 기본 평가

```bash
kubectl why eval -f <file.yaml>
```

### 네임스페이스 재정의

```bash
kubectl why eval -f deployment.yaml --namespace production
# 또는
kubectl why eval -f deployment.yaml -n production
```

### JSON 출력

```bash
kubectl why eval -f deployment.yaml -o json
```

### 사용자 정의 결정 디렉토리

```bash
kubectl why --dir /path/to/decisions eval -f deployment.yaml
```

## 예시

### 예시 1: 권한 있는 배포 평가

```bash
$ kubectl why eval -f testdata/privileged-deployment.yaml

WHY: Resource blocked: 1 critical, 1 high severity violations found
STATUS: BLOCKED

RESOURCE: Deployment/privileged-app
NAMESPACE: production
DECISION: eval-af07b28bf854
TIME: 2026-02-08T10:12:18Z

VIOLATIONS (2):
1) [CRITICAL] Privileged Container
   What: Container 'nginx' runs in privileged mode, which grants access to all host
   devices and bypasses security boundaries.
   Evidence:
     - (K8S_FIELD) spec.template.spec.containers[0].securityContext.privileged:
     privileged: true
   Fix (minimal):
     - Disable privileged mode: Set securityContext.privileged: false for container
     'nginx'
...

Saved decision eval-af07b28bf854 to ~/.kubectl-why/decisions/...

$ echo $?
2  # Exit code 2 = BLOCKED
```

### 예시 2: 안전한 배포 평가

```bash
$ kubectl why eval -f testdata/safe-deployment.yaml

WHY: Resource meets security requirements
STATUS: ALLOWED

RESOURCE: Deployment/safe-app
NAMESPACE: production
DECISION: eval-ff9af99d5fc8
TIME: 2026-02-08T10:12:26Z

Saved decision eval-ff9af99d5fc8 to ~/.kubectl-why/decisions/...

$ echo $?
0  # Exit code 0 = ALLOWED
```

### 예시 3: CI/CD를 위한 JSON 출력

```bash
kubectl why eval -f deployment.yaml -o json > decision.json
```

출력:
```json
{
  "schemaVersion": "v1",
  "decision": {
    "id": "eval-0c26a73edee4",
    "timestamp": "2026-02-08T10:12:36Z",
    "version": "v1alpha1",
    "status": "BLOCKED",
    "summary": "Resource blocked: 2 high severity violations found",
    "resource": {
      "kind": "Deployment",
      "name": "hostpath-app",
      "namespace": "default"
    },
    "violations": [...]
  }
}
```

## 결정 명령과의 통합

평가된 결정은 저장소에 저장되며 쿼리할 수 있습니다:

```bash
# 모든 결정 목록 조회 (eval된 결정 포함)
kubectl why decision list

# ID로 특정 결정 조회
kubectl why decision get eval-ff9af99d5fc8

# 리소스의 최신 결정 조회
kubectl why explain Deployment safe-app
```

## CI/CD 통합

자동화를 위해 종료 코드 사용:

```bash
#!/bin/bash
set -e

# 디렉토리의 모든 매니페스트 평가
for file in k8s/*.yaml; do
    echo "Evaluating $file..."
    if ! kubectl why eval -f "$file"; then
        echo "FAILED: $file violates security policies"
        exit 1
    fi
done

echo "All manifests passed security checks"
```

## 종료 코드

| 코드 | 의미 | 설명 |
|------|---------|-------------|
| 0    | SUCCESS | 리소스가 ALLOWED됨 (보안 요구사항 충족) |
| 1    | ERROR   | 런타임 오류 (잘못된 파일, 파싱 오류 등) |
| 2    | BLOCKED | 리소스가 BLOCKED됨 (보안 위반 사항 있음) |

## 지원되는 리소스 타입

현재 지원:
- Deployments (apps/v1)
- Pods (v1)
- StatefulSets (apps/v1)
- DaemonSets (apps/v1)

Pod 템플릿 스펙이 있는 모든 리소스가 평가됩니다.

## 정책 규칙

eval 명령은 온라인 평가자와 동일한 규칙을 적용합니다:

| 정책 ID | 심각도 | 설명 |
|-----------|----------|-------------|
| POL-SEC-001 | CRITICAL | 권한 있는 컨테이너 감지됨 |
| POL-SEC-002 | HIGH | HostPath 볼륨 감지됨 |
| POL-SEC-003 | HIGH | runAsNonRoot 설정되지 않음 |
| POL-SEC-004 | HIGH | 이미지가 :latest 태그 사용 또는 태그 없음 |

## 파일 형식

표준 Kubernetes YAML 또는 JSON 허용:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.2.3
        securityContext:
          runAsNonRoot: true
```

## 문제 해결

### 오류: 파일 읽기 실패

파일 경로가 올바르고 파일을 읽을 수 있는지 확인하세요:

```bash
ls -la testdata/deployment.yaml
kubectl why eval -f testdata/deployment.yaml
```

### 오류: 파일 파싱 실패

YAML이 유효한지 확인하세요:

```bash
yamllint deployment.yaml
# 또는
kubectl --dry-run=client -f deployment.yaml
```

### 위반 사항이 없는데 여전히 BLOCKED

리소스의 모든 컨테이너를 확인하세요 - 각 컨테이너는 적절한 보안 컨텍스트가 있어야 합니다.

## 다음 단계

- 모든 결정 보기: `kubectl why decision list`
- 결정 세부 정보 조회: `kubectl why decision get <id>`
- 다른 언어로 보기: `kubectl why --lang ko eval -f file.yaml`

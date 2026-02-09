# 워커 프로토콜 문서 (Worker Protocol Documentation)

이 문서는 Go 애플리케이션인 **kubectl-why**와 외부 Python 워커 간의 JSON 기반 연동 프로토콜을 정의합니다.

## 개요

Go 애플리케이션은 보안 결정(Security Decision)에 대한 설명을 선택적으로 워커에게 위임하거나 보강할 수 있습니다. 워커의 주요 역할은 더 나은 요약, 추가적인 인사이트, 그리고 번역을 제공하는 것입니다.

**중요하게도, 워커는 보안 결정의 허용(allow) 또는 차단(deny) 상태를 변경할 수 없습니다.** 워커는 기존 결정을 보강(enrichment)하는 역할만 수행합니다.

## 실행 모델

Go 애플리케이션은 표준 프로세스 실행 모델을 사용해 워커를 호출합니다.

- **입력(Input)**: Go 측은 WorkerRequest JSON을 워커의 **stdin**으로 전달합니다.
- **출력(Output)**: 워커는 WorkerResponse JSON을 자신의 **stdout**으로 출력합니다.
- **라이프사이클(Lifecycle)**: 요청마다 새로운 워커 프로세스를 실행할 수도 있고, 구현에 따라 지속 실행되는 프로세스를 사용할 수도 있습니다.

## 설정(Configuration)

워커 실행 명령은 환경 변수 또는 플래그로 지정할 수 있습니다.

- `WHY_WORKER_COMMAND`: 워커 실행 파일 경로 (예: `/usr/local/bin/why-worker` 또는 `python3 main.py`)
- `--worker-command`: 환경 변수를 덮어쓰기 위한 CLI 플래그

워커가 설정되지 않은 경우, `kubectl-why`는 규칙 기반(rule-only) 모드로 동작합니다.

## 버저닝 전략(Versioning Strategy)

프로토콜은 호환성을 보장하기 위해 버전 필드(예: `v1alpha1`)를 사용합니다.

- **추가 변경(Additive Changes)**: 기존 필드를 제거하지 않고 새로운 필드를 추가하는 경우, 메이저 버전을 올리지 않습니다.
- **하위 호환성(Backwards Compatibility)**: Go 측은 워커 응답에 포함된 알 수 없는 필드를 무시해야 합니다. 워커는 요청에 선택적 필드가 누락되더라도 정상적으로 처리해야 합니다.
- **파괴적 변경(Breaking Changes)**: 필드 제거 또는 구조 변경이 발생하는 경우, 새로운 버전(예: `v1`)이 필요합니다.

## 오류 처리(Error Handling)

- **워커 실패(Worker Failure)**: 워커가 비정상 종료되거나 실행에 실패하거나 타임아웃이 발생하면, Go 애플리케이션은 규칙 기반 설명으로 계속 진행하며 경고 로그를 남깁니다.
- **잘못된 JSON(Invalid JSON)**: 워커가 잘못된 JSON을 반환하거나 스키마와 맞지 않는 JSON을 반환하면, Go 측은 경고를 기록하고 워커 결과를 무시합니다.
- **요청 ID 누락(Missing Request ID)**: 워커는 요청에 포함된 `requestId`를 반드시 그대로 응답에 포함해야 합니다. 일치하지 않는 경우, 응답은 폐기될 수 있습니다.

## JSON 스키마(JSON Schemas)

다음 스키마들이 프로토콜 계약을 정의합니다.

1. `schemas/security-decision.schema.json`: 핵심 도메인 모델을 정의합니다.
2. `schemas/worker-request.schema.json`: 워커로 전달되는 요청의 구조를 정의합니다.
3. `schemas/worker-response.schema.json`: 워커로부터 기대하는 응답의 구조를 정의합니다.

## 설계 선택 사항(Design Choices)

- **JSON Schema Draft 2020-12**: 최신 기능과 도구 호환성을 위해 사용합니다.
- **camelCase**: Go 도메인 모델과의 일관성을 위해 모든 JSON 키는 camelCase를 사용합니다.
- **RFC3339**: 타임스탬프의 표준화를 위해 RFC3339 형식을 사용합니다.
- **관심사 분리(Separation of Concerns)**: 워커는 요약, 번역, 추가 액션 제안 등 설명 보강에만 집중하며, 최종 상태(ALLOWED/BLOCKED)에 대한 권한은 Go 애플리케이션이 유지합니다.
- **확장성(Extensibility)**: `metadata`와 `raw` 필드에는 `additionalProperties: true`를 허용해, 스키마 변경 없이 향후 데이터 타입을 확장할 수 있습니다.

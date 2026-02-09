# Rule Evaluator

This package provides real rule evaluation for Kubernetes resources against security policies.

## Overview

The `Evaluator` takes a Kubernetes resource specification (as a generic `map[string]interface{}`) and evaluates it against a set of security policies, producing a `SecurityDecision`.

## Policies Implemented

1. **POL-SEC-001**: Privileged Container (CRITICAL)
   - Blocks containers with `securityContext.privileged: true`

2. **POL-SEC-002**: HostPath Volume (HIGH)
   - Blocks volumes using `hostPath`

3. **POL-SEC-003**: Missing runAsNonRoot (HIGH)
   - Blocks containers without `securityContext.runAsNonRoot: true`

4. **POL-SEC-004**: Latest Image Tag (HIGH)
   - Blocks images using `:latest` tag or no tag

## Usage

```go
import (
    "time"
    "github.com/alisonui/why-blocked/internal/eval"
)

evaluator := eval.New("v1alpha1")

spec := map[string]interface{}{
    "apiVersion": "apps/v1",
    "kind":       "Deployment",
    "metadata": map[string]interface{}{
        "name":      "my-app",
        "namespace": "production",
    },
    "spec": map[string]interface{}{
        "template": map[string]interface{}{
            "spec": map[string]interface{}{
                "containers": []interface{}{
                    map[string]interface{}{
                        "name":  "app",
                        "image": "myapp:1.0.0",
                        "securityContext": map[string]interface{}{
                            "runAsNonRoot": true,
                        },
                    },
                },
            },
        },
    },
}

decision := evaluator.Evaluate(spec, time.Now(), "unique-decision-id")
// decision.Status will be ALLOWED or BLOCKED
// decision.Violations contains list of policy violations
```

## Running Tests

Run all evaluator tests:

```bash
go test ./internal/eval/... -v
```

Run a specific test:

```bash
go test ./internal/eval/... -v -run TestEvaluator_PrivilegedContainer
```

## Test Coverage

The test suite includes:

1. **TestEvaluator_PrivilegedContainer**: Verifies privileged containers are blocked with CRITICAL severity
2. **TestEvaluator_HostPathVolume**: Verifies hostPath volumes are blocked with HIGH severity
3. **TestEvaluator_RunAsNonRootMissing**: Verifies missing runAsNonRoot is blocked
4. **TestEvaluator_LatestImageTag**: Verifies :latest tag usage is blocked
5. **TestEvaluator_SafeBaseline**: Verifies compliant resources are allowed
6. **TestEvaluator_PodDirectly**: Verifies Pod resources (not just Deployments) are evaluated
7. **TestEvaluator_MultipleViolations**: Verifies multiple violations are detected

All tests use deterministic timestamps to ensure reproducibility.
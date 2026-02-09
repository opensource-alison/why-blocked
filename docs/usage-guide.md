# Offline Evaluation with `kubectl why eval`

The `eval` command enables offline security policy evaluation of Kubernetes YAML manifests without requiring cluster access.

## Features

- ✅ **Offline-first**: No Kubernetes cluster required
- ✅ **Real rule evaluation**: Uses the same evaluator as online checks
- ✅ **Persistent decisions**: Saved to repository for history tracking
- ✅ **Multiple output formats**: Text (default) or JSON
- ✅ **Exit codes**: 0 for ALLOWED, 2 for BLOCKED, 1 for errors

## Usage

### Basic Evaluation

```bash
kubectl why eval -f <file.yaml>
```

### With Namespace Override

```bash
kubectl why eval -f deployment.yaml --namespace production
# or
kubectl why eval -f deployment.yaml -n production
```

### JSON Output

```bash
kubectl why eval -f deployment.yaml -o json
```

### Custom Decision Directory

```bash
kubectl why --dir /path/to/decisions eval -f deployment.yaml
```

## Examples

### Example 1: Evaluate a Privileged Deployment

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

### Example 2: Evaluate a Safe Deployment

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

### Example 3: JSON Output for CI/CD

```bash
kubectl why eval -f deployment.yaml -o json > decision.json
```

Output:
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

## Integration with Decision Commands

Evaluated decisions are saved to the repository and can be queried:

```bash
# List all decisions (including eval'd ones)
kubectl why decision list

# Get specific decision by ID
kubectl why decision get eval-ff9af99d5fc8

# Get latest decision for a resource
kubectl why explain Deployment safe-app
```

## CI/CD Integration

Use exit codes for automation:

```bash
#!/bin/bash
set -e

# Evaluate all manifests in a directory
for file in k8s/*.yaml; do
    echo "Evaluating $file..."
    if ! kubectl why eval -f "$file"; then
        echo "FAILED: $file violates security policies"
        exit 1
    fi
done

echo "All manifests passed security checks"
```

## Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 0    | SUCCESS | Resource is ALLOWED (meets security requirements) |
| 1    | ERROR   | Runtime error (invalid file, parse error, etc.) |
| 2    | BLOCKED | Resource is BLOCKED (has security violations) |

## Supported Resource Types

Currently supports:
- Deployments (apps/v1)
- Pods (v1)
- StatefulSets (apps/v1)
- DaemonSets (apps/v1)

Any resource with a pod template spec will be evaluated.

## Policy Rules

The eval command applies the same rules as the online evaluator:

| Policy ID | Severity | Description |
|-----------|----------|-------------|
| POL-SEC-001 | CRITICAL | Privileged container detected |
| POL-SEC-002 | HIGH | HostPath volume detected |
| POL-SEC-003 | HIGH | runAsNonRoot not set |
| POL-SEC-004 | HIGH | Image uses :latest tag or no tag |

## File Format

Accepts standard Kubernetes YAML or JSON:

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

## Troubleshooting

### Error: Failed to read file

Make sure the file path is correct and the file is readable:

```bash
ls -la testdata/deployment.yaml
kubectl why eval -f testdata/deployment.yaml
```

### Error: Failed to parse file

Verify the YAML is valid:

```bash
yamllint deployment.yaml
# or
kubectl --dry-run=client -f deployment.yaml
```

### No violations but still BLOCKED

Check all containers in the resource - each container must have proper security context.

## Next Steps

- View all decisions: `kubectl why decision list`
- Get decision details: `kubectl why decision get <id>`
- View in different language: `kubectl why --lang ko eval -f file.yaml`

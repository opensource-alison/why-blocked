# Test Data for kubectl-why eval

This directory contains sample Kubernetes YAML manifests for testing the `eval` command.

## Files

### privileged-deployment.yaml

**Status**: BLOCKED
**Severity**: CRITICAL + HIGH

A Deployment with a privileged container that should trigger:
- POL-SEC-001 (CRITICAL): Privileged Container
- POL-SEC-003 (HIGH): Missing runAsNonRoot

```yaml
securityContext:
  privileged: true  # ← Violation
```

**Usage**:
```bash
kubectl why eval -f testdata/privileged-deployment.yaml
# Expected: BLOCKED with exit code 2
```

---

### safe-deployment.yaml

**Status**: ALLOWED

A secure Deployment that meets all security requirements:
- ✅ Specific image tag (not :latest)
- ✅ runAsNonRoot: true
- ✅ privileged: false
- ✅ ConfigMap volume (not hostPath)

**Usage**:
```bash
kubectl why eval -f testdata/safe-deployment.yaml
# Expected: ALLOWED with exit code 0
```

---

### hostpath-deployment.yaml

**Status**: BLOCKED
**Severity**: HIGH + HIGH

A Deployment using a hostPath volume that should trigger:
- POL-SEC-002 (HIGH): HostPath Volume
- POL-SEC-003 (HIGH): Missing runAsNonRoot

```yaml
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock  # ← Violation
```

**Usage**:
```bash
kubectl why eval -f testdata/hostpath-deployment.yaml
# Expected: BLOCKED with exit code 2
```

## Testing All Files

```bash
# Test all files at once
for file in testdata/*.yaml; do
  echo "Testing $file..."
  kubectl why eval -f "$file"
  echo "---"
done
```

## Creating New Test Cases

When adding new test YAML files:

1. Use realistic Kubernetes resource definitions
2. Include clear violations or security configurations
3. Add documentation here explaining the expected outcome
4. Update `cmd/why/eval_test.go` if needed

## Expected Results

| File | Status | Violations | Exit Code |
|------|--------|------------|-----------|
| privileged-deployment.yaml | BLOCKED | 2 (CRITICAL + HIGH) | 2 |
| safe-deployment.yaml | ALLOWED | 0 | 0 |
| hostpath-deployment.yaml | BLOCKED | 2 (HIGH + HIGH) | 2 |
